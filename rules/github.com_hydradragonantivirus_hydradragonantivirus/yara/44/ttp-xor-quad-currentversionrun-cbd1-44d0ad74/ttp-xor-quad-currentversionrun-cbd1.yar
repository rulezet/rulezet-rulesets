rule TTP_XOR_QUAD_CurrentVersionRun_cbd1 {
  strings:
    $key_cbd1 = { 98 be [2] bc b0 [2] 97 9c [2] b9 be [2] ad a5 [2] a2 bf [2] bc a2 [2] be a3 [2] a5 a5 [2] b9 a2 [2] a5 8d }

  condition:
    any of them
}