rule TTP_XOR_QUAD_CurrentVersionRun_7e21 {
  strings:
    $key_7e21 = { 2d 4e [2] 09 40 [2] 22 6c [2] 0c 4e [2] 18 55 [2] 17 4f [2] 09 52 [2] 0b 53 [2] 10 55 [2] 0c 52 [2] 10 7d }

  condition:
    any of them
}