rule TTP_XOR_QUAD_CurrentVersionRun_3ac9 {
  strings:
    $key_3ac9 = { 69 a6 [2] 4d a8 [2] 66 84 [2] 48 a6 [2] 5c bd [2] 53 a7 [2] 4d ba [2] 4f bb [2] 54 bd [2] 48 ba [2] 54 95 }

  condition:
    any of them
}