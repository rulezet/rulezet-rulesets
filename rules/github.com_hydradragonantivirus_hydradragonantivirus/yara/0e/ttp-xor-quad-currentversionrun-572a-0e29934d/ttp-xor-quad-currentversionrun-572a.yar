rule TTP_XOR_QUAD_CurrentVersionRun_572a {
  strings:
    $key_572a = { 04 45 [2] 20 4b [2] 0b 67 [2] 25 45 [2] 31 5e [2] 3e 44 [2] 20 59 [2] 22 58 [2] 39 5e [2] 25 59 [2] 39 76 }

  condition:
    any of them
}