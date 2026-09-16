rule Solarmarker_DLL_Jan2023
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Observed ASCII and Wide strings of obfuscated solarmarker dll"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $mz = "MZ"
      $wstring1 = "A+Aa+A" wide
      $astring1 = "hkResult" ascii
      $astring2 = "mscorlib" ascii
      $astring3 = "System.Reflection" ascii
      $astring4 = "CreateDecryptor" ascii
      $astring5 = "ToBase64String" ascii
  condition:
     $mz at 0 and $wstring1 and 1 of ($astring*)
}