rule winhttp_exe
{
       meta:
              description = "winhttp-exe"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "SeDebugPrivilege" wide ascii
              $b = "SearchInject" wide ascii
              $c = "Searcher.dll" wide ascii

       condition:
              $a and $b and $c
}