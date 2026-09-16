rule drovorub_unique_network_comms_strings {
    meta:
    description = "Rule to detect Drovorub-server, Drovorub-agent, or Drovorub-client based on unique network communication strings."

    strings:
        $s_01 = "action" wide ascii
        $s_02 = "auth.commit" wide ascii
        $s_03 = "auth.hello" wide ascii
        $s_04 = "auth.login" wide ascii
        $s_05 = "auth.pending" wide ascii
        $s_06 = "client_id" wide ascii
        $s_07 = "client_login" wide ascii
        $s_08 = "client_pass" wide ascii
        $s_09 = "clientid" wide ascii
        $s_10 = "clientkey_base64" wide ascii
        $s_11 = "file_list_request" wide ascii
        $s_12 = "module_list_request" wide ascii
        $s_13 = "monitor" wide ascii
        $s_14 = "net_list_request" wide ascii
        $s_15 = "server finished" wide ascii
        $s_16 = "serverid" wide ascii
        $s_17 = "tunnel" wide ascii
    condition:
        all of them
}