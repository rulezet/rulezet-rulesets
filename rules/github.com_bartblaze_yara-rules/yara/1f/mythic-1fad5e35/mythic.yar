rule Mythic
{
meta:
	id = "69R6s4O4jrRhzpA0GwJdh0"
	fingerprint = "v1_sha256_fd3f6ed7ae8191d98a0f7f3676795be2ab5656d7eed2fa5b4f452bd8610b9fa5"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Mythic, a collaborative, multi-platform, red teaming framework."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/its-a-feature/Mythic"
	tool = "MYTHIC"

strings:
	$ = "access_time"
	$ = "agent_callback_id"
	$ = "c2_profile"
	$ = "c2_profile_id"
	$ = "enc_key_base64"
	$ = "encrypted_exchange_check"
	$ = "file_browser"
	$ = "get_delegate_tasks"
	$ = "get_tasking"
	$ = "is_file"
	$ = "is_screenshot"
	$ = "post_response"
	$ = "send_webhook"
	$ = "task_id"
	$ = "tasking_size"
	$ = "total_chunks"
	$ = "webhook_alert"
	
condition:
	8 of them
}