rule TTP_XOR_QUAD_CurrentVersionRun_166c {
  strings:
    $key_166c = { 45 03 [2] 61 0d [2] 4a 21 [2] 64 03 [2] 70 18 [2] 7f 02 [2] 61 1f [2] 63 1e [2] 78 18 [2] 64 1f [2] 78 30 }

  condition:
    any of them
}