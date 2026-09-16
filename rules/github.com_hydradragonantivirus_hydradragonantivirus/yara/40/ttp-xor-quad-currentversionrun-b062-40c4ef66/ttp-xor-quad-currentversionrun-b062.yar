rule TTP_XOR_QUAD_CurrentVersionRun_b062 {
  strings:
    $key_b062 = { e3 0d [2] c7 03 [2] ec 2f [2] c2 0d [2] d6 16 [2] d9 0c [2] c7 11 [2] c5 10 [2] de 16 [2] c2 11 [2] de 3e }

  condition:
    any of them
}