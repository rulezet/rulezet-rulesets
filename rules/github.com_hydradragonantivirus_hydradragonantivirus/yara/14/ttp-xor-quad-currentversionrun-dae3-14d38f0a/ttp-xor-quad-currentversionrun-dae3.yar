rule TTP_XOR_QUAD_CurrentVersionRun_dae3 {
  strings:
    $key_dae3 = { 89 8c [2] ad 82 [2] 86 ae [2] a8 8c [2] bc 97 [2] b3 8d [2] ad 90 [2] af 91 [2] b4 97 [2] a8 90 [2] b4 bf }

  condition:
    any of them
}