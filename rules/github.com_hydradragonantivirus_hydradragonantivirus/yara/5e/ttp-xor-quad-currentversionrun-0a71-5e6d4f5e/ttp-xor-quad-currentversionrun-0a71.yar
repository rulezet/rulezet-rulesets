rule TTP_XOR_QUAD_CurrentVersionRun_0a71 {
  strings:
    $key_0a71 = { 59 1e [2] 7d 10 [2] 56 3c [2] 78 1e [2] 6c 05 [2] 63 1f [2] 7d 02 [2] 7f 03 [2] 64 05 [2] 78 02 [2] 64 2d }

  condition:
    any of them
}