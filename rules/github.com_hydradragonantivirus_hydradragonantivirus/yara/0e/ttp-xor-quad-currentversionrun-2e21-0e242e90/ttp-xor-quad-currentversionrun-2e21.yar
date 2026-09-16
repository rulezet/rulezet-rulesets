rule TTP_XOR_QUAD_CurrentVersionRun_2e21 {
  strings:
    $key_2e21 = { 7d 4e [2] 59 40 [2] 72 6c [2] 5c 4e [2] 48 55 [2] 47 4f [2] 59 52 [2] 5b 53 [2] 40 55 [2] 5c 52 [2] 40 7d }

  condition:
    any of them
}