rule c254853a {
  meta:
    description = "11-25-18 - file c254853a.ico"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-11-25"
    hash1       = "8a3d52b376a67a7833906ab4307e6614747c5c636768fc92b29f46735cdaa43d"

  strings:
            $s3 = "$_7il4m0k = basename/*1*/(/*2ro*/trim/*ag*/(/*j*/preg_replace/*vz*/(/*ds*/rawurldecode/*o*/(/*s4r9*/\"%2F%5C%28.%2A%24%2F\"/*085" ascii
    $s4 = "//61c050381e48e384c943fc94caeb742bb83%3Dy%20ko%26sses%3C7%22%3A%3B%2Ad%60da%3B%0Bs%20%2A%23mpnfkit%20%3Er%3E%3E1ogha~ce%60i9ks%7" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 200KB and
      (all of them)
    ) or (all of them)
}