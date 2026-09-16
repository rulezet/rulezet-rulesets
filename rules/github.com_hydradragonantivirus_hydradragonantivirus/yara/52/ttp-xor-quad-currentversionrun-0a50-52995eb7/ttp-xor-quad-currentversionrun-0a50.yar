rule TTP_XOR_QUAD_CurrentVersionRun_0a50 {
  strings:
    $key_0a50 = { 59 3f [2] 7d 31 [2] 56 1d [2] 78 3f [2] 6c 24 [2] 63 3e [2] 7d 23 [2] 7f 22 [2] 64 24 [2] 78 23 [2] 64 0c }

  condition:
    any of them
}