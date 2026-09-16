rule executable_win_pe_transposed_offbyone {
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
    $s1 = /Z.{76}ih srpgoar macnntob  eur nniD SOm do/

  condition:
    1 of them
}