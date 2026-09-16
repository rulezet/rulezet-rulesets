rule TTP_XOR_QUAD_CurrentVersionRun_aae3 {
  strings:
    $key_aae3 = { f9 8c [2] dd 82 [2] f6 ae [2] d8 8c [2] cc 97 [2] c3 8d [2] dd 90 [2] df 91 [2] c4 97 [2] d8 90 [2] c4 bf }

  condition:
    any of them
}