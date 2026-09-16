rule TTP_XOR_QUAD_CurrentVersionRun_fce3 {
  strings:
    $key_fce3 = { af 8c [2] 8b 82 [2] a0 ae [2] 8e 8c [2] 9a 97 [2] 95 8d [2] 8b 90 [2] 89 91 [2] 92 97 [2] 8e 90 [2] 92 bf }

  condition:
    any of them
}