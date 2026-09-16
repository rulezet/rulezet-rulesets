rule executable_win_reversed {
  meta:
    is_exe    = true
    type      = "win-reversed"
    rank      = 10
    revision  = "100"
    date      = "July 29 2015"
    desc      = "EXE is stored backwards"
    author    = "@tylabs"
    copyright = "QuickSand.io 2015"
    tlp       = "green"

  strings:
    $s1 = "edom SOD ni nur eb tonnac margorp sihT"  
  condition:
    1 of them
}