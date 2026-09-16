rule TTP_XOR_QUAD_CurrentVersionRun_921a {
  strings:
    $key_921a = { c1 75 [2] e5 7b [2] ce 57 [2] e0 75 [2] f4 6e [2] fb 74 [2] e5 69 [2] e7 68 [2] fc 6e [2] e0 69 [2] fc 46 }

  condition:
    any of them
}