rule RedDelta_c2 {
  meta:
    copyright = "Intezer Labs"
    author    = "Intezer Labs"
    reference = "https://www.intezer.com"

  strings:
    $str1 = "update.flach.cn"
    $str2 = "update.flach.com.cn"
    $str3 = "aHR0cDovL3VwZGF0ZS5mbGFjaC5jbg=="
    $str4 = "www.flach.cn"
    $str5 = "159.138.84.217"
    $str6 = "update.careerhuawei.net"
    $str7 = "aHR0cDovL3VwZGF0ZS5jYXJlZXJodWF3ZWkubmV0Ojgx"
    $str8 = "update1.jscachecdn.com"

  condition:
    any of them
}