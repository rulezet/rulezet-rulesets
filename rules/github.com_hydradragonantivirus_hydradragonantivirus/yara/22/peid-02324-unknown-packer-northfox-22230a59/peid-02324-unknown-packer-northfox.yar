rule PEiD_02324_Unknown_Packer____Northfox_ {
  meta:
    description = "[Unknown Packer -> Northfox]"
    ep_only     = "true"

  strings:
    $a = "TYhazy"

  condition:
    $a
}