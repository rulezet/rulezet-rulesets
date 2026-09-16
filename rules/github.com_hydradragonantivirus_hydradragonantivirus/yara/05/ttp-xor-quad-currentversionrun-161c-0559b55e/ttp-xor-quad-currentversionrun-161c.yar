rule TTP_XOR_QUAD_CurrentVersionRun_161c {
  strings:
    $key_161c = { 45 73 [2] 61 7d [2] 4a 51 [2] 64 73 [2] 70 68 [2] 7f 72 [2] 61 6f [2] 63 6e [2] 78 68 [2] 64 6f [2] 78 40 }

  condition:
    any of them
}