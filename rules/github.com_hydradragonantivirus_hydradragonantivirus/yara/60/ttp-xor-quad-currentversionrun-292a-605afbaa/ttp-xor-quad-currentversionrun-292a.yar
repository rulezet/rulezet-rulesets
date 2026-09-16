rule TTP_XOR_QUAD_CurrentVersionRun_292a {
  strings:
    $key_292a = { 7a 45 [2] 5e 4b [2] 75 67 [2] 5b 45 [2] 4f 5e [2] 40 44 [2] 5e 59 [2] 5c 58 [2] 47 5e [2] 5b 59 [2] 47 76 }

  condition:
    any of them
}