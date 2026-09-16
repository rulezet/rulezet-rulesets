rule TTP_XOR_QUAD_CurrentVersionRun_190c {
  strings:
    $key_190c = { 4a 63 [2] 6e 6d [2] 45 41 [2] 6b 63 [2] 7f 78 [2] 70 62 [2] 6e 7f [2] 6c 7e [2] 77 78 [2] 6b 7f [2] 77 50 }

  condition:
    any of them
}