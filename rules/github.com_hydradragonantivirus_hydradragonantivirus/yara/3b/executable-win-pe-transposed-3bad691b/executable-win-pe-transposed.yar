rule executable_win_pe_transposed {
  meta:
    is_exe    = true
    type      = "win"
    revision  = "100"
    rank      = 10
    date      = "Dec 27 2015"
    author    = "@tylabs"
    copyright = "QuickSand.io 2015"
    tlp       = "green"

  strings:
    $s1 = /ZM.{76}hTsip orrgma/

  condition:
    1 of them
}