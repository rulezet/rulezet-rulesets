rule TTP_XOR_QUAD_CurrentVersionRun_626d {
  strings:
    $key_626d = { 31 02 [2] 15 0c [2] 3e 20 [2] 10 02 [2] 04 19 [2] 0b 03 [2] 15 1e [2] 17 1f [2] 0c 19 [2] 10 1e [2] 0c 31 }

  condition:
    any of them
}