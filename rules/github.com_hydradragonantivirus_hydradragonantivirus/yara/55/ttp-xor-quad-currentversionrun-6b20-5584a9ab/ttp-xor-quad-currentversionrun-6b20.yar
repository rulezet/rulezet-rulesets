rule TTP_XOR_QUAD_CurrentVersionRun_6b20 {
  strings:
    $key_6b20 = { 38 4f [2] 1c 41 [2] 37 6d [2] 19 4f [2] 0d 54 [2] 02 4e [2] 1c 53 [2] 1e 52 [2] 05 54 [2] 19 53 [2] 05 7c }

  condition:
    any of them
}