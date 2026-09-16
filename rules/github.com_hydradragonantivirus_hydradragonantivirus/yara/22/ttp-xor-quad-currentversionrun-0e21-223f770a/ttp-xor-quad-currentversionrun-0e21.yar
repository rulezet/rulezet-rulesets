rule TTP_XOR_QUAD_CurrentVersionRun_0e21 {
  strings:
    $key_0e21 = { 5d 4e [2] 79 40 [2] 52 6c [2] 7c 4e [2] 68 55 [2] 67 4f [2] 79 52 [2] 7b 53 [2] 60 55 [2] 7c 52 [2] 60 7d }

  condition:
    any of them
}