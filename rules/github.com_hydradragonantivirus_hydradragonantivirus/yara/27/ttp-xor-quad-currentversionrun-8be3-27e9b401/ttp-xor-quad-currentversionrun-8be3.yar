rule TTP_XOR_QUAD_CurrentVersionRun_8be3 {
  strings:
    $key_8be3 = { d8 8c [2] fc 82 [2] d7 ae [2] f9 8c [2] ed 97 [2] e2 8d [2] fc 90 [2] fe 91 [2] e5 97 [2] f9 90 [2] e5 bf }

  condition:
    any of them
}