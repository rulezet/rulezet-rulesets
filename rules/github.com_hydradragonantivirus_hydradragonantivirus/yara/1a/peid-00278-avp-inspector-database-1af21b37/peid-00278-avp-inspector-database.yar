rule PEiD_00278_AVP_Inspector_Database_ {
  meta:
    description = "[AVP Inspector Database]"
    ep_only     = "false"

  strings:
    $a = "Ghost Buster"

  condition:
    $a
}