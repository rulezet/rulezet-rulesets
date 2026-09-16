rule TTP_XOR_QUAD_CurrentVersionRun_51bd {
  strings:
    $key_51bd = { 02 d2 [2] 26 dc [2] 0d f0 [2] 23 d2 [2] 37 c9 [2] 38 d3 [2] 26 ce [2] 24 cf [2] 3f c9 [2] 23 ce [2] 3f e1 }

  condition:
    any of them
}