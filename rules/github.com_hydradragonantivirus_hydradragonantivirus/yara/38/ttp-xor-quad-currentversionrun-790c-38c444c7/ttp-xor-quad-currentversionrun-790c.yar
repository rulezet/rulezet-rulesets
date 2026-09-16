rule TTP_XOR_QUAD_CurrentVersionRun_790c {
  strings:
    $key_790c = { 2a 63 [2] 0e 6d [2] 25 41 [2] 0b 63 [2] 1f 78 [2] 10 62 [2] 0e 7f [2] 0c 7e [2] 17 78 [2] 0b 7f [2] 17 50 }

  condition:
    any of them
}