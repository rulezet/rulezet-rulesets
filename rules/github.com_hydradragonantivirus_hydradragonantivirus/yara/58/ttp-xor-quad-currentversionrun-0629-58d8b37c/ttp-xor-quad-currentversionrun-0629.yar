rule TTP_XOR_QUAD_CurrentVersionRun_0629 {
  strings:
    $key_0629 = { 55 46 [2] 71 48 [2] 5a 64 [2] 74 46 [2] 60 5d [2] 6f 47 [2] 71 5a [2] 73 5b [2] 68 5d [2] 74 5a [2] 68 75 }

  condition:
    any of them
}