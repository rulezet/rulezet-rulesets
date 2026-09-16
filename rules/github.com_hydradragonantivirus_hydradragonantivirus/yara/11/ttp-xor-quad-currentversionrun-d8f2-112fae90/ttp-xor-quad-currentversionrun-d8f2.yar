rule TTP_XOR_QUAD_CurrentVersionRun_d8f2 {
  strings:
    $key_d8f2 = { 8b 9d [2] af 93 [2] 84 bf [2] aa 9d [2] be 86 [2] b1 9c [2] af 81 [2] ad 80 [2] b6 86 [2] aa 81 [2] b6 ae }

  condition:
    any of them
}