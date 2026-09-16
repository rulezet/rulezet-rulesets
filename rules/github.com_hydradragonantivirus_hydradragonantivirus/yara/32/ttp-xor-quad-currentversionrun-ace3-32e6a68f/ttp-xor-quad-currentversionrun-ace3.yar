rule TTP_XOR_QUAD_CurrentVersionRun_ace3 {
  strings:
    $key_ace3 = { ff 8c [2] db 82 [2] f0 ae [2] de 8c [2] ca 97 [2] c5 8d [2] db 90 [2] d9 91 [2] c2 97 [2] de 90 [2] c2 bf }

  condition:
    any of them
}