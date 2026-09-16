rule TTP_XOR_QUAD_CurrentVersionRun_167f {
  strings:
    $key_167f = { 45 10 [2] 61 1e [2] 4a 32 [2] 64 10 [2] 70 0b [2] 7f 11 [2] 61 0c [2] 63 0d [2] 78 0b [2] 64 0c [2] 78 23 }

  condition:
    any of them
}