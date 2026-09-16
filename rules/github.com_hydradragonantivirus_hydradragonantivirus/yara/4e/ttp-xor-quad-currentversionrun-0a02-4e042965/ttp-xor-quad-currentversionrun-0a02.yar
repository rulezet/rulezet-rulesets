rule TTP_XOR_QUAD_CurrentVersionRun_0a02 {
  strings:
    $key_0a02 = { 59 6d [2] 7d 63 [2] 56 4f [2] 78 6d [2] 6c 76 [2] 63 6c [2] 7d 71 [2] 7f 70 [2] 64 76 [2] 78 71 [2] 64 5e }

  condition:
    any of them
}