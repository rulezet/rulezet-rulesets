rule TTP_XOR_QUAD_CurrentVersionRun_cdc0 {
  strings:
    $key_cdc0 = { 9e af [2] ba a1 [2] 91 8d [2] bf af [2] ab b4 [2] a4 ae [2] ba b3 [2] b8 b2 [2] a3 b4 [2] bf b3 [2] a3 9c }

  condition:
    any of them
}