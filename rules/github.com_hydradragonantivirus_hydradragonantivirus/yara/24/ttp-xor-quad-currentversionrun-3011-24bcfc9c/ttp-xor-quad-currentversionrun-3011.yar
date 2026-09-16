rule TTP_XOR_QUAD_CurrentVersionRun_3011 {
  strings:
    $key_3011 = { 63 7e [2] 47 70 [2] 6c 5c [2] 42 7e [2] 56 65 [2] 59 7f [2] 47 62 [2] 45 63 [2] 5e 65 [2] 42 62 [2] 5e 4d }

  condition:
    any of them
}