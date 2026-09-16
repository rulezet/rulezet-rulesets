rule TTP_XOR_QUAD_CurrentVersionRun_232c {
  strings:
    $key_232c = { 70 43 [2] 54 4d [2] 7f 61 [2] 51 43 [2] 45 58 [2] 4a 42 [2] 54 5f [2] 56 5e [2] 4d 58 [2] 51 5f [2] 4d 70 }

  condition:
    any of them
}