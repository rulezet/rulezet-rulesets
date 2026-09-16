rule TTP_XOR_QUAD_CurrentVersionRun_921b {
  strings:
    $key_921b = { c1 74 [2] e5 7a [2] ce 56 [2] e0 74 [2] f4 6f [2] fb 75 [2] e5 68 [2] e7 69 [2] fc 6f [2] e0 68 [2] fc 47 }

  condition:
    any of them
}