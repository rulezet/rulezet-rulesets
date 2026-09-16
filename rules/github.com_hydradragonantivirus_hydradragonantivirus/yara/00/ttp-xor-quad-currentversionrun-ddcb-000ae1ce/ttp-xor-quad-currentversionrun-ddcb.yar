rule TTP_XOR_QUAD_CurrentVersionRun_ddcb {
  strings:
    $key_ddcb = { 8e a4 [2] aa aa [2] 81 86 [2] af a4 [2] bb bf [2] b4 a5 [2] aa b8 [2] a8 b9 [2] b3 bf [2] af b8 [2] b3 97 }

  condition:
    any of them
}