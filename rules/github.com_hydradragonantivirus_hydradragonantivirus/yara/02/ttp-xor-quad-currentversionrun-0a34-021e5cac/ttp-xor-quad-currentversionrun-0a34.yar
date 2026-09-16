rule TTP_XOR_QUAD_CurrentVersionRun_0a34 {
  strings:
    $key_0a34 = { 59 5b [2] 7d 55 [2] 56 79 [2] 78 5b [2] 6c 40 [2] 63 5a [2] 7d 47 [2] 7f 46 [2] 64 40 [2] 78 47 [2] 64 68 }

  condition:
    any of them
}