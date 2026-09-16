rule njrat : rat refined hardened
{
	meta:
		rule_group = "implant"
		implant = "njrat"
		description = "tested against NjRat versions 0.3.6 - 0.7d"
		organisation = "CSE"
		poc = "malware_dev@cse"
		rule_id = "CSE_900013"
		rule_version = "1"
		yara_version = "3.4"
		al_configdumper = "al_services.alsvc_configdecoder.dumpers.njRat.getConfig"
		al_configparser = "GenericParser"
		al_imported_by = "malware_dev"
		al_state_change_date = "2017-11-17"
		al_state_change_user = "stevegaron-cse"
		al_status = "DEPLOYED"
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		classification = "U"
		creation_date = "2017-02-27T18:32:28.956448Z"
		date = "2015-11-18"
		last_saved_by = "malware_dev"
		sample = "unpacked: 2b96518a66d251fedb39264e668f588c (0.7d)"
		type = "info"
		updated = "2015-11-18"
		version = "1"
		ruleset = "sample_rules.yar"
		repository = "CybercentreCanada/assemblyline-base"
		source_url = "https://github.com/CybercentreCanada/assemblyline-base/blob/ecfbf3c5b391196e90687421031b44352febdf58/assemblyline/odm/random_data/sample_rules.yar"
		license = "MIT License"
		score = 75

	strings:
		$cnc_traffic_0 = {7C 00 27 00 7C 00 27 00 7C}
		$rights_0 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 22 00}
		$rights_1 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 22 00}
		$overlap0 = {53 74 61 72 74 44 44 6f 73}
		$overlap1 = {53 74 6f 70 44 44 6f 73}
		$overlap2 = {58 57 6f 72 6d}
		$overlap3 = {58 63 68 61 74}
		$overlap4 = {58 4c 6f 67 67 65 72}

	condition:
		( all of ( $cnc_traffic_* ) ) and ( all of ( $rights_* ) ) and not ( any of ( $overlap* ) )
}