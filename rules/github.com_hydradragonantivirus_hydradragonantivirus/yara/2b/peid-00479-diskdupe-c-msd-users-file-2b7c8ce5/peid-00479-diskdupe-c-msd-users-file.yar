rule PEiD_00479_DiskDupe__c__MSD_Users_file_ {
  meta:
    description = "[DiskDupe (c) MSD Users file]"
    ep_only     = "false"

  strings:
    $a = "MSD Users Version"

  condition:
    $a
}