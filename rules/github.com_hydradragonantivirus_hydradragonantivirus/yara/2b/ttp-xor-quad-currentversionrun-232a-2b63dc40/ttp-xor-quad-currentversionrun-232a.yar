rule TTP_XOR_QUAD_CurrentVersionRun_232a {
  strings:
    $key_232a = { 70 45 [2] 54 4b [2] 7f 67 [2] 51 45 [2] 45 5e [2] 4a 44 [2] 54 59 [2] 56 58 [2] 4d 5e [2] 51 59 [2] 4d 76 }

  condition:
    any of them
}