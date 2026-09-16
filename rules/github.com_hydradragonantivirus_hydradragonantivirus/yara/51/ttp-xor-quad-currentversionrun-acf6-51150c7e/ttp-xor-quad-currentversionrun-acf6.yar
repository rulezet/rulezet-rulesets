rule TTP_XOR_QUAD_CurrentVersionRun_acf6 {
  strings:
    $key_acf6 = { ff 99 [2] db 97 [2] f0 bb [2] de 99 [2] ca 82 [2] c5 98 [2] db 85 [2] d9 84 [2] c2 82 [2] de 85 [2] c2 aa }

  condition:
    any of them
}