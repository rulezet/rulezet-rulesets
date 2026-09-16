rule Hacktools_CN_JoHor_Rdos_get {
  meta:
    description = "Disclosed hacktool set - file get.vbp"
    author      = "Florian Roth"
    date        = "17.11.14"
    score       = 60
    hash        = "09c32ca167136a17fd69df8c525ea5ffeca6c534"

  strings:
    $s1  = "http://dywt.com.cn" fullword ascii
    $s2  = "service@dywt.com.cn" fullword ascii
    $s3  = "Uncompress" fullword ascii
    $s5  = "GetNewInf" fullword ascii
    $s6  = "This is a runtime library file for EPL applications. The EPL is a software devel" ascii
    $s10 = "GetMD5" fullword ascii
    $s12 = "RSACheck" fullword ascii

  condition:
    all of them
}