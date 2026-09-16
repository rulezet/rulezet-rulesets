rule TTP_XOR_QUAD_CurrentVersionRun_6520 {
  strings:
    $key_6520 = { 36 4f [2] 12 41 [2] 39 6d [2] 17 4f [2] 03 54 [2] 0c 4e [2] 12 53 [2] 10 52 [2] 0b 54 [2] 17 53 [2] 0b 7c }

  condition:
    any of them
}