rule TTP_XOR_QUAD_CurrentVersionRun_302a {
  strings:
    $key_302a = { 63 45 [2] 47 4b [2] 6c 67 [2] 42 45 [2] 56 5e [2] 59 44 [2] 47 59 [2] 45 58 [2] 5e 5e [2] 42 59 [2] 5e 76 }

  condition:
    any of them
}