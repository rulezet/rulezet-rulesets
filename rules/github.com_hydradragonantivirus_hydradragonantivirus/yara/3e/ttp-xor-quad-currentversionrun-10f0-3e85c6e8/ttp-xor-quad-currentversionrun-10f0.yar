rule TTP_XOR_QUAD_CurrentVersionRun_10f0 {
  strings:
    $key_10f0 = { 43 9f [2] 67 91 [2] 4c bd [2] 62 9f [2] 76 84 [2] 79 9e [2] 67 83 [2] 65 82 [2] 7e 84 [2] 62 83 [2] 7e ac }

  condition:
    any of them
}