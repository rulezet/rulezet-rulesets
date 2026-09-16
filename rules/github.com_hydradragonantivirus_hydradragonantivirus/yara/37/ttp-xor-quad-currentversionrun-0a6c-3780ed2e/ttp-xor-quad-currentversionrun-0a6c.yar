rule TTP_XOR_QUAD_CurrentVersionRun_0a6c {
  strings:
    $key_0a6c = { 59 03 [2] 7d 0d [2] 56 21 [2] 78 03 [2] 6c 18 [2] 63 02 [2] 7d 1f [2] 7f 1e [2] 64 18 [2] 78 1f [2] 64 30 }

  condition:
    any of them
}