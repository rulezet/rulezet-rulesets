rule TTP_XOR_QUAD_CurrentVersionRun_8de3 {
  strings:
    $key_8de3 = { de 8c [2] fa 82 [2] d1 ae [2] ff 8c [2] eb 97 [2] e4 8d [2] fa 90 [2] f8 91 [2] e3 97 [2] ff 90 [2] e3 bf }

  condition:
    any of them
}